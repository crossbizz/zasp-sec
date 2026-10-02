package sessioncontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// The production store adds an immutable version receipt after a successful
// upload. Comparing that whole locator with the unversioned request loses it.
func TestComplianceExportAcceptsVersionedArtifactStoreReceipt(t *testing.T) {
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	value, err := BuildComplianceExport("export-version", []ComplianceEvidence{{
		Control:   ComplianceControl{ID: "control", Framework: "SOC 2", Name: "Access review", FreshUntil: now},
		Freshness: "missing",
	}})
	if err != nil {
		t.Fatal(err)
	}
	locator := complianceExportLocator(t)
	store, err := artifactstore.NewExport(&complianceVersionDriver{}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 8 * 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	result, err := WriteComplianceExportArtifact(context.Background(), store, locator.Scope, locator.Reference, value)
	if err != nil {
		t.Fatal(err)
	}
	if result.VersionID != "s3-version.1" || result.Scope != locator.Scope || result.Reference != locator.Reference {
		t.Fatalf("lost immutable artifact receipt: %+v", result.Locator)
	}
}

type complianceVersionDriver struct{}

func (*complianceVersionDriver) Put(_ context.Context, value artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	value.VersionID = "s3-version.1"
	return value, nil
}
func (*complianceVersionDriver) Get(context.Context, artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	return artifactstore.DriverObject{}, errors.New("unexpected get")
}
func (*complianceVersionDriver) Delete(context.Context, artifactstore.DriverLocator) error {
	return errors.New("unexpected delete")
}

func TestComplianceExportRejectsInvalidVersionAndChangedOwnership(t *testing.T) {
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	value, err := BuildComplianceExport("export-invalid", []ComplianceEvidence{{
		Control: ComplianceControl{ID: "control", Framework: "SOC 2", Name: "Access review", FreshUntil: now}, Freshness: "missing",
	}})
	if err != nil {
		t.Fatal(err)
	}
	locator := complianceExportLocator(t)
	for _, mode := range []string{"scope", "reference", "space", "newline", "nul", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			store := &complianceChangedReceiptStore{mode: mode}
			if _, err := WriteComplianceExportArtifact(context.Background(), store, locator.Scope, locator.Reference, value); !errors.Is(err, ErrRejected) {
				t.Fatalf("invalid receipt accepted: %v", err)
			}
		})
	}
}

type complianceChangedReceiptStore struct {
	complianceArtifactStore
	mode string
}

func (s *complianceChangedReceiptStore) Put(ctx context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	result, err := s.complianceArtifactStore.Put(ctx, request)
	switch s.mode {
	case "scope":
		result.Locator = artifactstore.Locator{Reference: result.Reference}
	case "reference":
		result.Locator = artifactstore.Locator{Scope: result.Scope}
	case "space":
		result.VersionID = "bad version"
	case "newline":
		result.VersionID = "bad\nversion"
	case "nul":
		result.VersionID = "bad\x00version"
	case "oversize":
		result.VersionID = strings.Repeat("v", 1025)
	}
	return result, err
}
