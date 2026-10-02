package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestAuditExportConfigureRunnerPinsResultAndFinalReadiness(t *testing.T) {
	config := AuditExportConfiguration{PolicyID: "pid_52000041-0000-4000-8000-000000000041", Bucket: "zasp-audit-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042", MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
	digest, _ := AuditExportPolicyDigest(config)
	for _, mode := range []string{"healthy", "wrong-policy-result", "final-drift"} {
		t.Run(mode, func(t *testing.T) {
			got := digest
			if mode == "wrong-policy-result" {
				got = strings.Repeat("0", 64)
			}
			rows := append(exactReleaseRows(append(productionAuditExportsPredecessors(), ProductionAuditExports())...), fakeRow{values: []any{true}}, fakeRow{values: []any{got}}, fakeRow{values: []any{mode != "final-drift"}})
			rows = append([]Row{fakeRow{values: []any{int64(52)}}}, rows...)
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			runner, _ := NewRunner(db)
			err := runner.ConfigureAuditExports(context.Background(), config)
			if (err == nil) != (mode == "healthy") {
				t.Fatal("configuration authority result", err)
			}
			events := strings.Join(db.events, "\n")
			if !strings.Contains(events, "zasp_audit_export_configure($1,$2,$3,$4,$5,$6,$7,$8,$9)") || strings.Contains(events, "commit") != (mode == "healthy") {
				t.Fatal("configuration did not enforce transaction result", events)
			}
		})
	}
	for _, runner := range []*Runner{nil, {}} {
		if !errors.Is(runner.ConfigureAuditExports(context.Background(), config), ErrInvalidRunner) {
			t.Fatal("invalid runner accepted")
		}
	}
	db := &fakeDatabase{}
	runner, _ := NewRunner(db)
	config.Bucket = "untrusted/path"
	if !errors.Is(runner.ConfigureAuditExports(context.Background(), config), ErrInvalidState) || len(db.events) != 0 {
		t.Fatal("invalid configuration reached database")
	}
}

func TestAuditExportPolicyDigestCanonicalBytes(t *testing.T) {
	configuration := AuditExportConfiguration{PolicyID: "pid_52000041-0000-4000-8000-000000000041", Bucket: "zasp-audit-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042", MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
	wire := `{"schema":"audit-export-policy-v1","policy_id":"pid_52000041-0000-4000-8000-000000000041","bucket":"zasp-audit-export-fixture","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}`
	digest := sha256.Sum256([]byte(wire))
	want := hex.EncodeToString(digest[:])
	if actual, err := AuditExportPolicyDigest(configuration); err != nil || actual != want {
		t.Fatal("trusted policy digest did not bind exact canonical fields", actual, err)
	}
	configuration.ExpectedCurrentPolicyID = "pid_52000043-0000-4000-8000-000000000043"
	if actual, err := AuditExportPolicyDigest(configuration); err != nil || actual != want {
		t.Fatal("CAS predecessor changed immutable policy digest", err)
	}
	for _, change := range []func(*AuditExportConfiguration){
		func(c *AuditExportConfiguration) { c.PolicyID = "bad" }, func(c *AuditExportConfiguration) { c.ExpectedCurrentPolicyID = "bad" },
		func(c *AuditExportConfiguration) { c.Bucket = "wrong.bucket" }, func(c *AuditExportConfiguration) { c.ExpectedBucketOwner = "123" }, func(c *AuditExportConfiguration) { c.KMSKeyARN = "arn:aws:kms:us-east-1:123456789012:alias/export" },
		func(c *AuditExportConfiguration) { c.MaximumExportBytes = 0 }, func(c *AuditExportConfiguration) { c.MaximumRetainedBytes = 1 << 53 }, func(c *AuditExportConfiguration) { c.MaximumInflight = 0 }, func(c *AuditExportConfiguration) { c.CaptureTimeoutSeconds = 121 },
	} {
		changed := configuration
		change(&changed)
		if _, err := AuditExportPolicyDigest(changed); err == nil {
			t.Fatal("malformed policy accepted")
		}
	}
}

func TestAuditExportRegisterWorkersRequiresBothReadinessChecks(t *testing.T) {
	for _, mode := range []string{"healthy", "registration-refused", "final-drift"} {
		t.Run(mode, func(t *testing.T) {
			rows := append(exactReleaseRows(append(productionAuditExportsPredecessors(), ProductionAuditExports())...), fakeRow{values: []any{true}}, fakeRow{values: []any{mode != "registration-refused"}}, fakeRow{values: []any{mode != "final-drift"}})
			rows = append([]Row{fakeRow{values: []any{int64(52)}}}, rows...)
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			runner, _ := NewRunner(db)
			err := runner.RegisterAuditExportWorkers(context.Background(), "audit_export_worker_fixture", "audit_export_outbox_fixture")
			if (err == nil) != (mode == "healthy") {
				t.Fatal("worker registration result", err)
			}
			events := strings.Join(db.events, "\n")
			if !strings.Contains(events, "zasp_audit_export_register_workers($1,$2)") || strings.Contains(events, "commit") != (mode == "healthy") {
				t.Fatal("worker registration transaction", events)
			}
		})
	}
	for _, runner := range []*Runner{nil, {}} {
		if !errors.Is(runner.RegisterAuditExportWorkers(context.Background(), "worker", "outbox"), ErrInvalidRunner) {
			t.Fatal("invalid registration runner accepted")
		}
	}
}

func TestAuditExportConfigurationOnBudgetReleasePinsAuthority(t *testing.T) {
	config := AuditExportConfiguration{PolicyID: "pid_52000041-0000-4000-8000-000000000041", Bucket: "zasp-audit-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/52000042-0000-4000-8000-000000000042", MaximumExportBytes: 1 << 30, MaximumRetainedBytes: 10 << 30, MaximumInflight: 2, CaptureTimeoutSeconds: 120}
	digest, _ := AuditExportPolicyDigest(config)
	for _, releaseVersion := range []int64{53, 54, 55} {
		for _, operation := range []string{"configure", "register", "api"} {
			for _, mode := range []string{"healthy", "lower-version", "future", "wrong-checksum", "wrong-selected-checksum", "initial-drift", "final-drift"} {
				t.Run(operation+"/"+mode, func(t *testing.T) {
					metadata := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets())
					if releaseVersion >= 54 {
						metadata = append(metadata, ProductionSecurityAgentRunContext())
					}
					if releaseVersion == 55 {
						metadata = append(metadata, ProductionSecurityAgentExistingTests())
					}
					if mode == "wrong-checksum" {
						metadata[52].checksum = "wrong"
					}
					if mode == "wrong-selected-checksum" {
						metadata[len(metadata)-1].checksum = "wrong"
					}
					count := releaseVersion
					if mode == "lower-version" {
						count = 51
					}
					if mode == "future" {
						count = 56
					}
					rows := append([]Row{fakeRow{values: []any{count}}}, exactReleaseRows(metadata...)...)
					var result any = digest
					if operation != "configure" {
						result = true
					}
					rows = append(rows, fakeRow{values: []any{mode != "initial-drift"}}, fakeRow{values: []any{result}}, fakeRow{values: []any{mode != "final-drift"}})
					db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
					runner, _ := NewRunner(db)
					var err error
					if operation == "configure" {
						err = runner.ConfigureAuditExports(context.Background(), config)
					} else if operation == "api" {
						err = runner.RegisterAuditExportAPI(context.Background(), "export_api")
					} else {
						err = runner.RegisterAuditExportWorkers(context.Background(), "export_worker", "export_outbox")
					}
					events := strings.Join(db.events, "\n")
					if (err == nil) != (mode == "healthy") || strings.Contains(events, "commit") != (mode == "healthy") {
						t.Fatalf("mode=%s err=%v events=%s", mode, err, events)
					}
					if mode == "healthy" || mode == "final-drift" {
						readyName, fingerprint, checksum := "zasp_production_security_agent_budgets_readiness", SecurityAgentBudgetCandidateFingerprint(), ProductionSecurityAgentBudgets().Checksum()
						if releaseVersion == 54 {
							readyName, fingerprint, checksum = "zasp_production_security_agent_run_context_readiness", SecurityAgentRunContextFingerprint(), ProductionSecurityAgentRunContext().Checksum()
						}
						if releaseVersion == 55 {
							readyName, fingerprint, checksum = "zasp_production_security_agent_existing_tests_readiness", SecurityAgentExistingTestsFingerprint(), ProductionSecurityAgentExistingTests().Checksum()
						}
						if strings.Count(events, readyName) != 2 || !strings.Contains(events, fingerprint) || !strings.Contains(events, checksum) {
							t.Fatalf("missing compiled pre/post budget authority: %s", events)
						}
					} else if strings.Contains(events, "zasp_audit_export_configure(") || strings.Contains(events, "zasp_audit_export_register_workers(") || strings.Contains(events, "zasp_audit_export_register_api(") {
						t.Fatalf("unsafe release reached mutation: %s", events)
					}
				})
			}
		}
	}
}

// Wrong52 name/checksum, a missing predecessor, and an unknown future release
// must not make the runner report a supported deployment version.
func TestProductionAuditExportsRunnerVersion(t *testing.T) {
	releases := append(productionAuditExportsPredecessors(), ProductionAuditExports())
	for _, test := range []struct {
		name   string
		mutate func([]Metadata) []Metadata
		want   int64
	}{
		{"healthy", func(rows []Metadata) []Metadata { return rows }, 52},
		{"wrong52name", func(rows []Metadata) []Metadata { rows[51].name = "wrong"; return rows }, 0},
		{"wrong52checksum", func(rows []Metadata) []Metadata { rows[51].checksum = "wrong"; return rows }, 0},
		{"wrong51checksum", func(rows []Metadata) []Metadata { rows[50].checksum = "wrong"; return rows }, 0},
		{"gap", func(rows []Metadata) []Metadata { return append(rows[:49], rows[50:]...) }, 0},
		{"unknown53", func(rows []Metadata) []Metadata {
			return append(rows, Metadata{version: 53, name: "unknown", checksum: "wrong"})
		}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := test.mutate(append([]Metadata(nil), releases...))
			database := &fakeDatabase{rows: append([]Row{fakeRow{values: []any{true}}}, exactReleaseRows(rows...)...)}
			runner, _ := NewRunner(database)
			version, err := runner.Version(context.Background())
			if test.want == 52 {
				if version != 52 || err != nil {
					t.Fatal(version, err)
				}
			} else if version != 0 || err == nil {
				t.Fatal("accepted malformed release", version, err)
			}
		})
	}
}

func TestProductionAuditExportsInvalidRunner(t *testing.T) {
	for _, runner := range []*Runner{nil, {}} {
		if !errors.Is(runner.UpProductionAuditExports(context.Background()), ErrInvalidRunner) || !errors.Is(runner.DownProductionAuditExports(context.Background()), ErrInvalidRunner) {
			t.Fatal("invalid runner accepted")
		}
	}
}
