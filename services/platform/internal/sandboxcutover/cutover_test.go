package sandboxcutover

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// This fixture owns a local approval record. It is deliberately not a
// production provenance verifier, database fence, or Kubernetes implementation.
type fixture struct {
	t                                              *testing.T
	release                                        ReleaseBinding
	now                                            time.Time
	calls                                          []string
	verifyErr, dispatchErr, reconcileErr, fenceErr error
	responseAudit, reconcileAudit                  string
	cleanup, dispatches                            int
	inside                                         bool
	fencedCapture                                  Capture
	initialRecords                                 []ReceiptRecord
	receiptBody, archiveBody                       []byte
	visible                                        [][]sessionsearch.Document
	failAt                                         string
	deadline                                       time.Time
	observeOffset                                  time.Duration
	onStep                                         func(string)
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, now: time.Now().UTC(), reconcileErr: errors.New("not observed")}
	f.release = ReleaseBinding{
		ArtifactDigest:   strings.Repeat("a", 64),
		From:             Manifest{50, "backfill", "zasp-runtime-sessions-v1", strings.Repeat("b", 64), strings.Repeat("d", 64)},
		To:               Manifest{50, "query", "zasp-runtime-sessions-v2", strings.Repeat("c", 64), strings.Repeat("d", 64)},
		KubernetesServer: "https://cluster.example", KubernetesCADigest: strings.Repeat("e", 64), Namespace: "agentsec", NamespaceUID: "namespace-1",
		DatabaseIdentity: "database-fixture-1", ProviderIdentity: "search-fixture-1",
	}
	f.fencedCapture = Capture{Digest: strings.Repeat("f", 64), Records: []ReceiptRecord{}}
	return f
}

func (f *fixture) deps() Dependencies {
	return Dependencies{f, f, f, f, f, f, func() time.Time { return f.now }, func() string { return "transition-1" }}
}

func (f *fixture) step(ctx context.Context, name string) error {
	f.calls = append(f.calls, name)
	if f.onStep != nil {
		f.onStep(name)
	}
	if f.inside {
		d, ok := ctx.Deadline()
		if !ok || d.After(f.deadline) {
			f.t.Fatalf("%s escaped remaining fence deadline", name)
		}
	}
	if name == f.failAt {
		return errors.New("fixture failure")
	}
	return ctx.Err()
}
func (f *fixture) Verify(ctx context.Context, ref string) (ReleaseBinding, error) {
	if ref != "approved-fixture" {
		f.t.Fatal("release reference changed", ref)
	}
	f.step(ctx, "verify")
	return f.release, f.verifyErr
}
func (f *fixture) Capture(ctx context.Context, _ ReleaseBinding) (Capture, error) {
	if f.initialRecords != nil {
		return Capture{Digest: strings.Repeat("f", 64), Records: f.initialRecords}, f.step(ctx, "capture")
	}
	return Capture{Digest: strings.Repeat("f", 64), Records: []ReceiptRecord{}}, f.step(ctx, "capture")
}

type fixtureFence struct{ f *fixture }

func (g fixtureFence) Ready(ctx context.Context) error { return g.f.step(ctx, "fence-ready") }
func (g fixtureFence) Capture(ctx context.Context) (Capture, error) {
	return g.f.fencedCapture, g.f.step(ctx, "recapture")
}
func (g fixtureFence) AliveAt(ctx context.Context) (time.Time, error) {
	return g.f.now, g.f.step(ctx, "alive")
}
func (f *fixture) WithFence(ctx context.Context, _ ReleaseBinding, fn func(Fence) error) (FenceResult, error) {
	f.calls = append(f.calls, "fence")
	d, ok := ctx.Deadline()
	if !ok || time.Until(d) > 15*time.Second {
		f.t.Fatal("unbounded fence")
	}
	f.deadline = d
	f.inside = true
	defer func() { f.inside = false; f.cleanup++ }()
	err := fn(fixtureFence{f})
	if f.fenceErr != nil {
		return FenceResult{CleanupConfirmed: false}, errors.Join(err, f.fenceErr)
	}
	return FenceResult{CleanupConfirmed: true}, err
}
func (f *fixture) Read(ctx context.Context, _ ReleaseBinding, _ ReceiptRecord) ([]byte, []byte, error) {
	return f.receiptBody, f.archiveBody, f.step(ctx, "artifacts")
}
func (f *fixture) Ready(ctx context.Context) error { return f.step(ctx, "search-ready") }
func (f *fixture) VerifyVisibleDocuments(ctx context.Context, documents []sessionsearch.Document) error {
	f.visible = append(f.visible, documents)
	return f.step(ctx, "search-visible")
}
func (f *fixture) ObserveBackfill(ctx context.Context, _ ReleaseBinding) (Observation, error) {
	return Observation{f.now.Add(f.observeOffset), strings.Repeat("1", 64), APIIdentity{"api-1", "opaque-version", f.release.From.APITemplateDigest}}, f.step(ctx, "observe")
}
func (f *fixture) RevalidateBackfill(ctx context.Context, _ ReleaseBinding, old Observation) (Observation, error) {
	return old, f.step(ctx, "revalidate")
}
func (f *fixture) DispatchQuery(ctx context.Context, b ReleaseBinding, old APIIdentity, a Audit) (AppliedState, error) {
	f.step(ctx, "dispatch")
	f.dispatches++
	if old.UID != "api-1" || old.ResourceVersion != "opaque-version" || a.TransitionID != "transition-1" || a.ReceiptCount != len(f.initialRecords) || a.ReceiptSetDigest != strings.Repeat("f", 64) || a.ReleaseDigest != strings.Repeat("a", 64) || b.To.APIIndex != "zasp-runtime-sessions-v2" {
		f.t.Fatal("dispatch authority changed", old, a, b)
	}
	if f.responseAudit != "" {
		a.TransitionID = f.responseAudit
	}
	return AppliedState{APIIdentity{old.UID, "result-version", b.To.APITemplateDigest}, a}, f.dispatchErr
}

func fixtureWithReceipt(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	org, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(org, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	f.archiveBody = []byte(`{"source":"tetragon","events":[{"event_id":"cutover-event-1","class":"file","action":"write","workload_id":"runtime-a","event_time":"2026-09-09T10:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","content":{"path_digest":"redacted"}}]}`)
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, f.archiveBody)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: scope, BatchID: environment, Generation: 1, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(f.archiveBody), Body: f.archiveBody, Correlations: []runtimecorrelation.Result{{EventID: decoded.Records[0].ID, Confidence: domain.EvidenceConfidenceUnattributed}}})
	if err != nil {
		t.Fatal(err)
	}
	receipt := runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: scope, BatchID: environment, Generation: 1, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-v1", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(f.archiveBody), EffectDigest: projected.ContentDigest, Items: projected.Items}
	body, digest, _, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.receiptBody = body
	binding := sessionsearch.ReceiptBinding{Scope: scope, BatchID: environment, Generation: 1, ReceiptDigest: digest}
	documents, err := sessionsearch.BuildDocuments(binding, body, f.archiveBody)
	if err != nil {
		t.Fatal(err)
	}
	f.initialRecords = []ReceiptRecord{{Binding: binding, ReceiptReference: "s3://zasp-evidence/project.json", ReceiptVersion: "project-v1", ProjectVersion: "runtime-projection-v1", CompleteVersion: "runtime-complete-v1", EventIDs: []string{decoded.Records[0].ID.String()}, DocumentIDs: []string{documents[0].DocumentID}}}
	f.fencedCapture.Records = f.initialRecords
	return f
}

func TestCutoverVerifiesCanonicalReceiptBeforeDispatch(t *testing.T) {
	f := fixtureWithReceipt(t)
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Applied || len(f.visible) != 1 || len(f.visible[0]) != 1 || f.visible[0][0].Action != "write" || f.visible[0][0].OrganizationID != "pid_10000001-0000-4000-8000-000000000001" || f.visible[0][0].InvestigationID != "unattributed" || r.Audit.ReceiptCount != 1 {
		t.Fatal(r, f.calls, f.visible)
	}
}

func TestCutoverArtifactOrVisibilityFailureCannotDispatch(t *testing.T) {
	for _, failure := range []string{"altered-archive", "altered-receipt", "artifacts", "search-visible", "wrong-document-id"} {
		t.Run(failure, func(t *testing.T) {
			f := fixtureWithReceipt(t)
			switch failure {
			case "altered-archive":
				f.archiveBody = []byte("{}")
			case "altered-receipt":
				f.receiptBody = []byte("{}")
			case "wrong-document-id":
				f.initialRecords[0].DocumentIDs = []string{"wrong"}
			default:
				f.failAt = failure
			}
			r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
			if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 0 {
				t.Fatal(r, f.calls)
			}
		})
	}
}
func (f *fixture) Reconcile(ctx context.Context, b ReleaseBinding, a Audit) (AppliedState, error) {
	f.step(ctx, "reconcile")
	if f.reconcileAudit != "" {
		a.TransitionID = f.reconcileAudit
	}
	return AppliedState{APIIdentity{"api-1", "result-version", b.To.APITemplateDigest}, a}, f.reconcileErr
}

func TestCutoverDispatchesOnlyOnce(t *testing.T) {
	f := newFixture(t)
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Applied || r.Rollout != Pending || f.dispatches != 1 || f.cleanup != 1 || r.Audit.TransitionID != "transition-1" || !r.CleanupConfirmed {
		t.Fatalf("result=%+v dispatches=%d cleanup=%d", r, f.dispatches, f.cleanup)
	}
	want := []string{"verify", "observe", "capture", "search-ready", "fence", "fence-ready", "recapture", "revalidate", "search-ready", "alive", "dispatch"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("unsafe order: %v", f.calls)
	}
}

func TestCutoverRejectsUnverifiedReleaseBeforeDependencies(t *testing.T) {
	f := newFixture(t)
	f.verifyErr = errors.New("untrusted")
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || r.Rollout != NotStarted || !reflect.DeepEqual(f.calls, []string{"verify"}) {
		t.Fatal(r, f.calls)
	}
}

func TestCutoverClosedTransition(t *testing.T) {
	for name, change := range map[string]func(*ReleaseBinding){
		"schema49":         func(b *ReleaseBinding) { b.From.SchemaVersion = 49 },
		"schema51":         func(b *ReleaseBinding) { b.To.SchemaVersion = 51 },
		"already-query":    func(b *ReleaseBinding) { b.From.APIIndex = "zasp-runtime-sessions-v2" },
		"worker-changed":   func(b *ReleaseBinding) { b.To.OtherResourcesDigest = strings.Repeat("9", 64) },
		"wrong-phase":      func(b *ReleaseBinding) { b.To.Phase = "precision-intake" },
		"empty-provenance": func(b *ReleaseBinding) { b.ArtifactDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(&f.release)
			r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
			if r.Outcome != Refused || !reflect.DeepEqual(f.calls, []string{"verify"}) {
				t.Fatal(r, f.calls)
			}
		})
	}
}

func TestCutoverInvalidDependenciesHaveNoCalls(t *testing.T) {
	for _, name := range []string{"nil-context", "typed-nil", "missing-clock", "missing-id"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			d := f.deps()
			ctx := context.Background()
			switch name {
			case "nil-context":
				ctx = nil
			case "typed-nil":
				var missing *fixture
				d.Releases = missing
			case "missing-clock":
				d.Now = nil
			case "missing-id":
				d.NewTransitionID = nil
			}
			r := ExecuteSandboxQueryCutover(ctx, Request{"approved-fixture"}, d)
			if r.Outcome != Refused || len(f.calls) != 0 {
				t.Fatal(r, f.calls)
			}
		})
	}
}

func TestCutoverLostResponseIsIndeterminate(t *testing.T) {
	f := newFixture(t)
	f.dispatchErr = context.DeadlineExceeded
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Indeterminate || f.dispatches != 1 || f.cleanup != 1 {
		t.Fatal(r, f.calls)
	}
}
func TestCutoverReconcilesAppliedResponse(t *testing.T) {
	f := newFixture(t)
	f.dispatchErr = context.DeadlineExceeded
	f.reconcileErr = nil
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Applied || f.dispatches != 1 || f.cleanup != 1 {
		t.Fatal(r, f.calls)
	}
}
func TestCutoverDefiniteCASRejectionIsRefused(t *testing.T) {
	f := newFixture(t)
	f.dispatchErr = ErrCASRefused
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || f.dispatches != 1 || f.cleanup != 1 || f.calls[len(f.calls)-1] != "dispatch" {
		t.Fatal(r, f.calls)
	}
}
func TestCutoverDoesNotCreditAnotherTransition(t *testing.T) {
	f := newFixture(t)
	f.responseAudit = "other"
	f.reconcileErr = nil
	f.reconcileAudit = "other"
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Indeterminate || f.dispatches != 1 {
		t.Fatal(r, f.calls)
	}
}
func TestCutoverCleanupFailureCannotEraseApplied(t *testing.T) {
	f := newFixture(t)
	f.fenceErr = errors.New("connection lost after apply")
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Applied || r.CleanupConfirmed || f.dispatches != 1 {
		t.Fatal(r, f.calls)
	}
}
func TestCutoverFenceFailuresCannotDispatch(t *testing.T) {
	for _, step := range []string{"fence-ready", "recapture", "revalidate", "alive"} {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			f.failAt = step
			r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
			if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 1 {
				t.Fatal(r, f.calls)
			}
		})
	}
}

func TestCutoverRefusalRetainsConfirmedCleanup(t *testing.T) {
	f := newFixture(t)
	f.failAt = "fence-ready"
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 1 || !r.CleanupConfirmed {
		t.Fatal("refused operation lost confirmed fence release", r, f.calls)
	}
}
func TestCutoverChangedCompleteSetCannotDispatch(t *testing.T) {
	f := newFixture(t)
	f.fencedCapture.Digest = strings.Repeat("0", 64)
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 1 {
		t.Fatal(r, f.calls)
	}
}

func TestCutoverObservationExpiryCannotDispatch(t *testing.T) {
	for _, offset := range []time.Duration{-30 * time.Second, time.Second} {
		f := newFixture(t)
		f.observeOffset = offset
		r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
		if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 0 {
			t.Fatal(r, f.calls)
		}
	}
	f := newFixture(t)
	f.onStep = func(step string) {
		if step == "revalidate" {
			f.now = f.now.Add(30 * time.Second)
		}
	}
	r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 1 {
		t.Fatal(r, f.calls)
	}
}

func TestCutoverRemainingFenceDeadlinePropagates(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	r := ExecuteSandboxQueryCutover(ctx, Request{"approved-fixture"}, f.deps())
	if r.Outcome != Applied || f.deadline != want {
		t.Fatal(r, f.deadline, want)
	}
}

func TestCutoverCancellationBeforeDispatchCannotApply(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onStep = func(step string) {
		if step == "alive" {
			cancel()
		}
	}
	r := ExecuteSandboxQueryCutover(ctx, Request{"approved-fixture"}, f.deps())
	if r.Outcome != Refused || f.dispatches != 0 || f.cleanup != 1 {
		t.Fatal(r, f.calls)
	}
}

func TestCutoverEveryTypedNilBoundaryIsRejected(t *testing.T) {
	var absent *fixture
	for name, mutate := range map[string]func(*Dependencies){
		"database":   func(d *Dependencies) { d.Database = absent },
		"artifacts":  func(d *Dependencies) { d.Artifacts = absent },
		"search":     func(d *Dependencies) { d.Search = absent },
		"observer":   func(d *Dependencies) { d.Observer = absent },
		"kubernetes": func(d *Dependencies) { d.Kubernetes = absent },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			d := f.deps()
			mutate(&d)
			r := ExecuteSandboxQueryCutover(context.Background(), Request{"approved-fixture"}, d)
			if r.Outcome != Refused || len(f.calls) != 0 {
				t.Fatal(r, f.calls)
			}
		})
	}
}
