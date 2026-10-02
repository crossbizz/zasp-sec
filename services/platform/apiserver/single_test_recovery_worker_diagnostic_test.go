package apiserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const singleRecoveryWorkerSourceFile = "security_agent_temporal_single_recovery_live_test.go"

var singleRecoveryWorkerLocationPattern = regexp.MustCompile(`security_agent_temporal_single_recovery_live_test\.go:([0-9]{1,3}):`)
var singleRecoveryWorkerSQLStatePattern = regexp.MustCompile(`SQLSTATE ([0-9A-Z]{5})`)

func singleRecoveryWorkerFailureView(output []byte) []byte {
	filtered := singleRecoveryContentionBoundaryPattern.ReplaceAll(output, nil)
	filtered = singleRecoveryQueryTracePattern.ReplaceAll(filtered, nil)
	return singleRecoveryRelayPattern.ReplaceAll(filtered, nil)
}

var singleRecoveryRelayPattern = regexp.MustCompile(`(?m)^[ \t]*security_agent_temporal_single_recovery_live_test\.go:[0-9]{1,4}: recovery-relay failure=(none|pending|attempt|start|ack|overall) completed=(none|pending|attempt|start|ack) class=(none|deadline|canceled|query|response|conflict|unavailable|invalid|other) sqlstate=(none|22023|25001|22P02|23505|23514|40001|40P01|42501|55P03|57014|other) elapsed=(lt1s|lt5s|lt10s|lt30s|ge30s) total=(lt1s|lt5s|lt10s|lt30s|ge30s)\r?$`)

func singleRecoveryRelaySummary(output []byte) string {
	fields := singleRecoveryRelayPattern.FindSubmatch(output)
	if len(fields) != 7 {
		return ""
	}
	return " relay=" + string(fields[1]) + "/" + string(fields[2]) + "/" + string(fields[3]) + "/" + string(fields[4]) + "/" + string(fields[5]) + "/" + string(fields[6])
}

type singleRecoveryWorkerSourceBinding struct {
	contains string
	stage    string
}

// These source locations are part of the diagnostic overlay, not product
// authority. Unknown or moved locations remain unclassified until reviewed.
var singleRecoveryWorkerSourceBindings = map[int]singleRecoveryWorkerSourceBinding{
	34:  {"t.Fatal(err)", "endpoint"},
	40:  {`t.Fatal("owned loopback fixture required")`, "owner-config"},
	44:  {`t.Fatal("owner pool")`, "owner-pool"},
	49:  {`t.Fatal("original run required")`, "run"},
	63:  {`t.Fatal("registered fixture pool")`, "role-pool"},
	71:  {`t.Fatal("durable API command and captured input required")`, "command"},
	75:  {`t.Fatal("captured input manifest")`, "manifest"},
	77:  {"newRecoveryNativeComposition(", "composition"},
	80:  {`t.Fatal("reviewed native source prerequisite")`, "runtime-ready"},
	84:  {`t.Fatal("captured journal prerequisite")`, "journal-ready"},
	88:  {"t.Fatal(err)", "product"},
	95:  {`t.Fatal("stopped unknown-debt fixture required")`, "fixture-stop"},
	100: {`t.Fatal("debt baseline")`, "debt-baseline"},
	103: {`t.Fatal("unknown evidence did not preserve pending debt", err)`, "debt-pending"},
	106: {`t.Fatal("unknown evidence changed debt/capacity or sent IO")`, "debt-immutable"},
	111: {`t.Fatal("immutable identity baseline")`, "identity-baseline"},
	122: {`t.Fatal("contention barrier transaction")`, "contention-begin"},
	130: {`t.Fatal("contention lock")`, "contention-lock"},
	171: {`t.Fatal("pre-settlement contention barrier or join", e)`, "contention-join"},
	176: {`t.Fatal("unknown-evidence caller did not remain pending", i, result)`, "contention-pending"},
	179: {`t.Fatal("first-settlement caller was not complete or retryable", i, result)`, "contention-settlement"},
	183: {`t.Fatal("contention changed immutable identity")`, "contention-identity"},
	186: {`t.Fatal("contention attempted fresh provider/target authorization")`, "contention-io"},
	191: {"contend(true)", "contention-pending"},
	193: {`t.Fatal("contended unknown evidence changed debt/capacity or sent IO")`, "contention-debt"},
	199: {`t.Fatal("late observation source")`, "late-source"},
	211: {`t.Fatal("late observation shape")`, "late-shape"},
	217: {`t.Fatal("late observation roster")`, "late-roster"},
	225: {`t.Fatal("native late observation recording", err)`, "late-record"},
	228: {`t.Fatal("duplicate late observation", err)`, "late-replay"},
	233: {`t.Fatal("native invocation baseline")`, "invocation-baseline"},
	238: {"contend(false)", "contention-settle"},
	242: {`t.Fatal("namespace client")`, "namespace-client"},
	248: {`t.Fatal("missing original history fixture")`, "original-observation"},
	255: {`t.Fatal("recovery worker")`, "worker-start"},
	263: {`t.Fatal("durable command relay", err)`, "relay"},
	267: {`t.Fatal("actual cleanup workflow", err)`, "workflow"},
	272: {`t.Fatal("first committed receipt/artifact identity")`, "proof-first"},
	275: {`t.Fatal("same immutable command duplicate", err)`, "duplicate-start"},
	278: {`t.Fatal("receipt-safe repeated cleanup", err)`, "repeat-cleanup"},
	297: {`t.Fatal("concurrent settled cleanup", e)`, "settled-contention"},
	302: {`t.Fatal("native idempotency or invocation preservation")`, "final-idempotency"},
	305: {`t.Fatal("settled replay changed receipt or artifact identity")`, "receipt-replay"},
	313: {`t.Fatal("recovery created fresh target IO")`, "no-fresh-io"},
	316: {`t.Fatal("final recovery changed immutable identity")`, "identity-final"},
	329: {`t.Fatal("negative proof transaction")`, "negative-tx"},
	338: {`t.Fatal("forged settled successor accepted")`, "forged-settled"},
	346: {`t.Fatal("forged command accepted")`, "forged-command"},
	349: {`t.Fatal("valid command damaged by forgery")`, "forgery-preservation"},
}

var singleRecoveryWorkerSQLStates = map[string]struct{}{
	"22023": {},
	"22P02": {},
	"23505": {},
	"23514": {},
	"40001": {},
	"42501": {},
	"55P03": {},
	"57014": {},
}

var singleRecoveryWorkerReasons = []struct {
	literal string
	label   string
}{
	{"verified cleanup proof pending", "cleanup-pending"},
	{"orchestration command rejected", "invalid"},
	{"orchestration input conflict", "conflict"},
	{"orchestration unavailable", "unavailable"},
}

func singleRecoveryWorkerFailure(ctx context.Context, output []byte, cause error) error {
	contextState := "live"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		contextState = "deadline"
	} else if errors.Is(ctx.Err(), context.Canceled) {
		contextState = "canceled"
	}
	exitState := "failed"
	if contextState == "deadline" || errors.Is(cause, context.DeadlineExceeded) {
		exitState = "deadline"
	} else if contextState == "canceled" || errors.Is(cause, context.Canceled) {
		exitState = "canceled"
	}

	testState := "unknown"
	for _, marker := range []struct {
		literal string
		state   string
	}{
		{"--- FAIL: TestSingleTestRecoveryConnectedTemporal (", "fail"},
		{"--- SKIP: TestSingleTestRecoveryConnectedTemporal (", "skip"},
		{"--- PASS: TestSingleTestRecoveryConnectedTemporal (", "pass"},
	} {
		if strings.Contains(string(output), marker.literal) {
			testState = marker.state
			break
		}
	}

	failureView := singleRecoveryWorkerFailureView(output)
	source, stage := "unknown", "unknown"
	if match := singleRecoveryWorkerLocationPattern.FindSubmatch(failureView); len(match) == 2 {
		if line, err := strconv.Atoi(string(match[1])); err == nil {
			if binding, ok := singleRecoveryWorkerSourceBindings[line]; ok {
				source = singleRecoveryWorkerSourceFile + ":" + strconv.Itoa(line)
				stage = binding.stage
			}
		}
	}

	reason := ""
	for _, candidate := range singleRecoveryWorkerReasons {
		if strings.Contains(string(output), candidate.literal) {
			reason = candidate.label
			break
		}
	}

	sqlState := ""
	if match := singleRecoveryWorkerSQLStatePattern.FindSubmatch(output); len(match) == 2 {
		candidate := string(match[1])
		if _, ok := singleRecoveryWorkerSQLStates[candidate]; ok {
			sqlState = candidate
		}
	}

	return fmt.Errorf("connected worker failed context=%s exit=%s test=%s source=%s stage=%s reason=%s sqlstate=%s%s%s%s%s", contextState, exitState, testState, source, stage, reason, sqlState, singleRecoveryContentionDetail(failureView, source, stage), singleRecoveryContentionBoundarySummary(output), singleRecoveryQueryTraceSummary(output), singleRecoveryRelaySummary(output))
}

// Read only the first classified failure line. Every returned value is a
// fixed label; neither child output nor an error tail is copied into the result.
func singleRecoveryContentionDetail(output []byte, source, stage string) string {
	if !strings.HasPrefix(stage, "contention-") {
		return ""
	}
	index := strings.Index(string(output), source+": ")
	if index < 0 {
		return ""
	}
	message := strings.SplitN(string(output)[index+len(source)+2:], "\n", 2)[0]
	for _, assertion := range []struct {
		literal, label string
		caller         bool
	}{
		{"contention barrier transaction", "begin", false},
		{"contention lock", "lock", false},
		{"pre-settlement contention barrier or join", "wait-join", false},
		{"unknown-evidence caller did not remain pending", "pending-result", true},
		{"first-settlement caller was not complete or retryable", "settlement-result", true},
		{"contention changed immutable identity", "identity", false},
		{"contention attempted fresh provider/target authorization", "fresh-io", false},
	} {
		if message != assertion.literal && !strings.HasPrefix(message, assertion.literal+" ") {
			continue
		}
		tail := strings.TrimPrefix(message, assertion.literal)
		caller, detail := "none", "unknown"
		if fields := strings.Fields(tail); assertion.caller && len(fields) > 0 {
			switch fields[0] {
			case "0":
				caller = "cleanup"
			case "1":
				caller = "step"
			case "2":
				caller = "finish"
			}
		}
		for _, candidate := range []struct{ literal, label string }{
			{"contention caller did not join", "unjoined"},
			{"unexpected contention participant", "participant"},
			{"contention began after first settlement", "already-settled"},
			{"context deadline exceeded", "deadline"},
			{"context canceled", "canceled"},
			{"verified cleanup proof pending", "pending"},
			{"orchestration command rejected", "invalid"},
			{"orchestration input conflict", "conflict"},
			{"orchestration unavailable", "unavailable"},
		} {
			if strings.Contains(tail, candidate.literal) {
				detail = candidate.label
				break
			}
		}
		return fmt.Sprintf(" assertion=%s caller=%s detail=%s", assertion.label, caller, detail)
	}
	return ""
}
