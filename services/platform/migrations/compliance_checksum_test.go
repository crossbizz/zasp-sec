package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestComplianceChecksumPreservesOriginalMetadata(t *testing.T) {
	for _, tc := range []struct {
		metadata         func() Metadata
		checksum, sqlSHA string
		size             int
	}{
		{ProductionSecurityAgentBudgets, "7abc79563337471bed669f3366f3fce9c2dd6a11b79d9621ebd982835168699b", "850c4b514824a94a56a54c9e8eb55524696bf3b42a4a41fa34cc22b99e0f9600", 96608},
		{ProductionSecurityAgentRunContext, "f968ed4c073cf05ee15af7f6b4c125b919c910f611bb433ca60f6e686e03158e", "42f127ad2e6e7de177935ef566343c531f4f36770d70d9bda02a430d3b75fba3", 52939},
		{ProductionSecurityAgentExistingTests, "01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00", "4b36212a103d0a3576b0161334e1e5da8d07fab41afec2d05f9e32a651e18c58", 331486},
		{ProductionCompliance, "f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1", "cc660e450ae8253bddfaee6f7f0422388df1e81bfc5dc4cf65ffccc8083746b0", 85410},
	} {
		m := tc.metadata()
		sum := sha256.Sum256([]byte(m.UpSQL()))
		if m.Checksum() != tc.checksum || hex.EncodeToString(sum[:]) != tc.sqlSHA || len(m.UpSQL()) != tc.size {
			t.Fatalf("release%d original metadata identity changed", m.Version())
		}
	}
	if got := ComplianceChecksum(); got != "f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1" {
		t.Fatal("checksum-only DAG identity changed", got)
	}
}
func TestComplianceChecksumObservesLiveSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source *string
	}{
		{"BudgetFragment", &securityAgentBudgetAdmissionCandidate}, {"ContextFragment", &securityAgentRunContextProjectionSQL}, {"ExistingEnqueue", &securityAgentExistingTestEnqueueSQL}, {"ExistingSettlement", &securityAgentExistingTestSettlementSQL}, {"ComplianceJobs", &complianceJobsSQL}, {"ComplianceDown", &complianceDownSQL}, {"AuditExportsPredecessor", &productionAuditExportsUpSQL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := *tc.source
			before := ComplianceChecksum()
			defer func() { *tc.source = original }()
			*tc.source = original + "\n-- changed-source observation\n"
			changed := ComplianceChecksum()
			if changed == before || changed != ProductionCompliance().Checksum() {
				t.Fatal("live source changed without exact DAG identity recomputation")
			}
			*tc.source = original
			if ComplianceChecksum() != before {
				t.Fatal("restored source identity differs")
			}
		})
	}
}

func TestWorkerReadinessChecksumObservesLiveSources(t *testing.T) {
	const expected = "206fedba804bf0862daa656e3a835fc3dc294682a7bd18eda5608d22b7943eb1"
	if SecurityAgentWorkerChecksum() != expected || ProductionSecurityAgentWorker().Checksum() != expected {
		t.Fatal("original worker63 identity changed")
	}
	for _, source := range []*string{&securityAgentWorkerUpSQL, &securityAgentWorkerDownSQL} {
		original := *source
		func() {
			defer func() { *source = original }()
			*source = original + "\n-- changed source observation\n"
			changed := SecurityAgentWorkerChecksum()
			if changed == expected || changed != ProductionSecurityAgentWorker().Checksum() {
				t.Fatal("worker checksum failed exact live source recomputation")
			}
		}()
		if SecurityAgentWorkerChecksum() != expected {
			t.Fatal("worker checksum did not restore")
		}
	}
}
