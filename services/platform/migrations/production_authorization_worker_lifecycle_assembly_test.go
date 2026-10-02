package migrations

import (
	"regexp"
	"strings"
	"testing"
)

func TestSingleTestRecoveryStopSuccessorCopyRejectsAmbiguousSource(t *testing.T) {
	source := ProductionTemporalTestExecutor().UpSQL()
	got := authorizationWorkerStopSuccessor(source)
	f := recoveryFindBody(got, "zasp_authorization80_worker.test74_stop_evidence(text,text,text,text)")
	original := recoveryFindBody(source, "zasp_temporal74.stop_evidence(text,text,text,text)")
	// The sole inserted arm can be removed to recover the entire original body.
	// Missing, repeated, or substituted insertion anchors must refuse assembly.
	if strings.Replace(f.body, workerSettledStopArm, "", 1) != original.body {
		t.Fatal("successor changed a predecessor predicate or return")
	}
	for _, bad := range []string{source + source, strings.Replace(source, workerStopParentAnchor, "", 1), strings.Replace(source, workerStopParentAnchor, workerStopParentAnchor+workerStopParentAnchor, 1)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("ambiguous predecessor accepted")
				}
			}()
			_ = authorizationWorkerStopSuccessor(bad)
		}()
	}
}

// A module inserted after pin expansion must not emit placeholder strings as
// runtime version predicates. Exercise the real SQL builder's output; native
// lifecycle tests separately prove that PostgreSQL accepts the emitted profile.
func TestWorkerLifecycleAssemblyEmitsCompiledPins(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	start := strings.Index(source, "DO $recovery_status_reader$")
	end := strings.Index(source, "END $recovery_status_reader$;")
	if start < 0 || end <= start {
		t.Fatal("assembled profile lacks the recovery status reader")
	}
	reader := source[start:end]
	for _, pin := range []struct {
		field string
		want  string
	}{
		{"checksum", ProductionTemporalTestExecutor().Checksum()},
		{"fingerprint", TemporalTestExecutorFingerprint()},
	} {
		matches := regexp.MustCompile(`q->>'`+pin.field+`'='([^']*)'`).FindAllStringSubmatch(reader, -1)
		if len(matches) != 1 {
			t.Fatalf("expected one emitted %s predicate, got %d", pin.field, len(matches))
		}
		if matches[0][1] != pin.want {
			t.Errorf("emitted lifecycle %s is %q, want compiled native pin %q", pin.field, matches[0][1], pin.want)
		}
	}
}
