package apiserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestP7OrderedCurrentCaptureComposition installs the accepted source once and
// runs the three independently bounded catalog consumers against that same
// installation. The outputs remain noninstallable local evidence until their
// separate intake and review gates accept them.
func TestP7OrderedCurrentCaptureComposition(t *testing.T) {
	mode := os.Getenv("ZASP_ORDERED_CURRENT_CAPTURE_COMPOSITION")
	if mode == "" {
		t.Skip("explicit ordered-current capture composition required")
	}
	if mode != "1" {
		t.Fatal("ordered-current capture composition mode refused")
	}
	for _, name := range []string{"ZASP_ORDERED_DIRECT_FRAME_ACCEPTANCE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE", "ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE", "ZASP_ORDERED_PRIVATE_REFERENCE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_CAPTURE"} {
		if os.Getenv(name) != "" {
			t.Fatalf("ordered-current capture composition overlaps %s", name)
		}
	}

	direct, err := loadOrderedDirectFrameAcceptancePacket(orderedDirectFrameAcceptancePacketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	validateOrderedDirectFrameAcceptancePacket(t, direct)
	missing, err := loadOrderedMissingReferenceNativePacket(orderedMissingReferenceNativePacketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, err := os.ReadFile(orderedCurrentPrivateSuccessorPacketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	privatePacket, err := decodeOrderedCurrentPrivateSuccessorPacket(privateRaw, orderedCurrentPrivateSuccessorPacketSHA256)
	if err != nil {
		t.Fatal(err)
	}
	privateOutput := os.Getenv("ZASP_ORDERED_PRIVATE_SUCCESSOR_OUTPUT")
	if !filepath.IsAbs(privateOutput) || filepath.Clean(privateOutput) != privateOutput {
		t.Fatal("private-successor composition output must be a new absolute path")
	}
	if _, err := os.Lstat(privateOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private-successor composition output already exists")
	}

	directCapture := orderedDirectFrameCatalogCapture(direct)
	missingCapture := orderedMissingReferenceCatalogCapture(missing)
	privateCapture := orderedCurrentPrivateSuccessorCatalogCapture(privatePacket, privateRaw, privateOutput)
	combined := ordered68CatalogCapture(func(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
		t.Helper()
		if !directCapture(t, ctx, owner) {
			t.Fatal("direct-frame composition capture did not complete")
		}
		if !missingCapture(t, ctx, owner) {
			t.Fatal("missing-reference composition capture did not complete")
		}
		if !privateCapture(t, ctx, owner) {
			t.Fatal("private-successor composition capture did not complete")
		}
		return true
	})
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, combined, nil)
}
